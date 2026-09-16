rule PEiD_00547_Escargot_0_1___by_ueMeat_ {
  meta:
    description = "[Escargot 0.1 - by ueMeat]"
    ep_only     = "true"

  strings:
    $a = { EB 08 28 65 73 63 30 2E 31 29 60 68 2B ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 5C ?? ?? ?? 8B 00 FF D0 50 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B }

  condition:
    $a
}