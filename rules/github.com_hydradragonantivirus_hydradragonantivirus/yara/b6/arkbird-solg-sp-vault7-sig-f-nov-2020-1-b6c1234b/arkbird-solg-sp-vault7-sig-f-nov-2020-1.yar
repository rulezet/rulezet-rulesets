rule ARKBIRD_SOLG_SP_Vault7_SIG_F_Nov_2020_1: FILE {
  meta:
    description = "Detect open-source PasswordReminder recovery tools used by Chinese APT in the Past"
    author      = "Arkbird_SOLG"
    id          = "0b65e333-16e2-57c3-84f0-5cd24c9d9593"
    date        = "2020-11-30"
    modified    = "2020-11-30"
    reference   = "Internal Research"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-11-30/SP_Vault7_SIG_F_Nov_2020_1.yar#L1-L23"
    license_url = "N/A"
    logic_hash  = "b03ffb433491b532d891f29aeb5b33c6578067f2f05845514a7bdc1e50f88a10"
    score       = 75
    quality     = 75
    tags        = "FILE"
    hash1       = "e6e17f2b2ce0ae07cf48654156b79ee90d330961456f731e84c94f50fe34f802"
    hash2       = "c224ee5bef42a45e84e0d5a409d8b4c3842b2a7ac3fe5006ee795e64e0778e6e"

  strings:
    $dbg1 = "PasswordReminder is unable to find WinLogon or you are using NWGINA.DLL.\n"
    $dbg2 = "The encoded password is found at 0x%8.8lx and has a length of %d.\n"
    $dbg3 = "PasswordReminder is unable to find the password in memory.\n"
    $dbg4 = " Usage: %s DomainName UserName PID-of-WinLogon\n\n"
    $dbg5 = "The logon information is: %S/%S/%S.\n"
    $dbg6 = "The WinLogon process id is %d (0x%8.8lx).\n"
    $dbg7 = "You logged on at %d/%d/%d %d:%d:%d\n"
    $dbg8 = "The hash byte is: 0x%2.2x.\n"
    $dbg9 = { 53 55 56 57 68 14 ?? 40 00 e8 17 0c 00 00 8b 6c 24 1c [1-4] 45 00 50 68 e0 ?? 40 00 e8 ?? ?? 00 00 83 c4 ?? e8 ?? 02 00 00 85 c0 75 1d e8 ?? 02 00 00 85 c0 75 14 68 b4 ?? 40 00 e8 ?? 0b 00 00 83 c4 04 33 c0 5f 5e 5d 5b }

  condition:
    uint16(0) == 0x4d5a and filesize > 50KB and 6 of them
}