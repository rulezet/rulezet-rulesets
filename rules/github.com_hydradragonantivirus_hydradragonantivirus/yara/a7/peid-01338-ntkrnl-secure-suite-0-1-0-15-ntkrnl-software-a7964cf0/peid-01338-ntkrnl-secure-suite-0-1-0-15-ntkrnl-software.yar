rule PEiD_01338_NTkrnl_Secure_Suite_0_1_0_15____NTkrnl_Software_ {
  meta:
    description = "[NTkrnl Secure Suite 0.1-0.15 -> NTkrnl Software]"
    ep_only     = "true"

  strings:
    $a = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }

  condition:
    $a
}