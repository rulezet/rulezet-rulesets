rule ARKBIRD_SOLG_MAL_Heinote_June_2020_1: FILE {
  meta:
    description = "Detect Hienote malware"
    author      = "Arkbird_SOLG"
    id          = "5c0e604a-83d4-5c6f-83fa-0df878da80d8"
    date        = "2020-06-26"
    modified    = "2023-11-22"
    reference   = "https://twitter.com/JAMESWT_MHT/status/1276471822217891840"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-26/Heinote_June_2020-1.yar#L1-L29"
    license_url = "N/A"
    logic_hash  = "679f1113c9c770910d18da395b13aaef009ecdde91a0c11f931d0d7e63ed122a"
    score       = 75
    quality     = 61
    tags        = "FILE"
    hash1       = "e0a34b9c420ddd930b3f89c13c3f564907dd948e88f668a0fe55ce506220bd73"

  strings:
    $s1  = "[DEBUGINFO][LOCK][SET]----"
    $s2  = "[DEBUGINFO][LOCK][GET]----"
    $s3  = "[DEBUGINFO][LOCK][GET][SHHelper] GetMainPage lpszurl = %s"
    $s4  = "[DEBUGINFO][LOCK][SET][SHHelper] status = %d/%d get = %s set = %s"
    $s5  = "DebugInfo"
    $s6  = "[DEBUGINFO][FAV][SET]----"
    $s7  = "[DEBUGINFO][FAV][SET][SHHelper] fav ret = %d\n"
    $s8  = "[DEBUGINFO][FAV][SET][SHHelper] i = %d lpszMagic = %s\n"
    $s9  = "[DEBUGINFO][SETCOOKIEHAO123] ok ok\n"
    $s10 = "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%08x, qop=%s, response=\"%s\""
    $s11 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" fullword ascii
    $s12 = "%s cookie %s=\"%s\" for domain %s, path %s, expire %I64d\n"
    $s13 = "User-Agent: %s" fullword ascii
    $s14 = "Send failure: %s" fullword ascii
    $s15 = "ftp://%s:%s@%s" fullword ascii
    $s16 = "Host: %s%s%s" fullword ascii
    $s17 = "Referer: %s" fullword ascii

  condition:
    uint16(0) == 0x4D5A and filesize < 450KB and 14 of them
}