rule PEiD_02426_UPX_Modified_stub_ {
  meta:
    description = "[UPX Modified stub]"
    ep_only     = "true"

  strings:
    $a = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF }

  condition:
    $a
}