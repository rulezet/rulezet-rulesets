rule PEiD_00947_JExeCompressor_V1_0____UsAr_ {
  meta:
    description = "[JExeCompressor V1.0 -> UsAr]"
    ep_only     = "true"

  strings:
    $a = { 0F C8 0F CF C6 C4 8B 0F AC EA 99 0F AD D8 13 F5 0F BD EF 85 EF 85 DA 69 FE ?? ?? ?? ?? 21 F9 BE ?? ?? ?? ?? 23 CF 0F BC FE D2 DC 85 EF B9 ?? ?? ?? ?? C6 C0 F7 8D 35 ?? ?? ?? ?? 8D 0D }

  condition:
    $a
}