rule ARKBIRD_SOLG_MAL_OSX_Wizardupdate_Oct_2021_2: FILE {
  meta:
    description = "Detect a structure like the bash of WizardUpdate installer on OSX system"
    author      = "Arkbird_SOLG"
    id          = "3e48c2fa-10f4-5152-90e6-f5f8cc507103"
    date        = "2021-10-22"
    modified    = "2021-10-23"
    reference   = "https://twitter.com/MsftSecIntel/status/1451279679059488773"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-10-23/WizardUpdate/MAL_OSX_WizardUpdate_Oct_2021_2.yara#L1-L20"
    license_url = "N/A"
    logic_hash  = "99d3323e3c155be040fef3beea0a55aec9bd3178df822d5fd6530864186446ed"
    score       = 75
    quality     = 67
    tags        = "FILE"
    hash1       = "eafacc44666901a5ea3c81a128e5dd88d0968a400d74ef1da5c2c05dc6dd7a39"
    tlp         = "White"
    adversary   = "-"

  strings:
    $s1 = "$(eval echo ~$(echo $USER))"
    $s2 = { 69 66 20 5b 20 21 20 2d 66 20 22 24 [5-15] 22 20 5d 3b 20 74 68 65 6e }
    $s3 = { 63 75 72 6c 20 2d 2d 72 65 74 72 79 20 [2-3] 2d 66 20 22 }
    $s4 = "xattr -r -d com.apple.quarantine"
    $s5 = "launchctl load -w"
    $s6 = "chown -R $USER"
    $s7 = "<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>\n\t<!DOCTYPE plist PUBLIC \\\"-//Apple//DTD PLIST 1.0//EN\\\" \\\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\\\">\n\t<plist version=\\\"1.0\\\">"

  condition:
    filesize > 2KB and 6 of ($s*)
}