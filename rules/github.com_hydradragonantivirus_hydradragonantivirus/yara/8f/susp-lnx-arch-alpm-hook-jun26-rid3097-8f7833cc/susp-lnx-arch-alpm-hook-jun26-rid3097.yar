rule SUSP_LNX_ARCH_ALPM_Hook_Jun26_RID3097: DEMO LINUX SUSP {
  meta:
    description = "Detects suspicious execution commands in Arch ALPM hooks"
    author      = "Marius Benthin"
    reference   = "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency"
    date        = "2026-06-15 12:46:21"
    score       = 70
    customer    = "demo"
    license     = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"

    tags         = "DEMO, LINUX, SUSP"
    minimum_yara = "3.5.0"

  strings:
    $s1 = "[Action]"
    $s2 = "Exec = "
    $s3 = "npm install "
    $s4 = "2>/dev/null"

  condition:
    filesize < 5KB and all of them
}