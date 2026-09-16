rule NK_GOLDBACKDOOR_obf_payload {
  meta:
    author      = "Silas Cutler (silas@Stairwell.com)"
    description = "Detection for encoded shellcode payload downloaded by LNK file that drops GOLDBACKDOOR"
    reference   = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
    version     = "0.1"

  strings:
    $init = { e6 b3 6d 0a 65 02 1e 67 0a ee e7 e6 e6 6b ea c2 }

  condition:
    $init at 0
}