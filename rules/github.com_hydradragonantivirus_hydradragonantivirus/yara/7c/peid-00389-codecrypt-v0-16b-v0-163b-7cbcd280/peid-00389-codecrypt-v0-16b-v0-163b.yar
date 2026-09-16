import "pe"
rule PEiD_00389_CodeCrypt_v0_16b___v0_163b_ {
  meta:
    description = "[CodeCrypt v0.16b - v0.163b]"
    ep_only     = "true"

  strings:
    $a = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

  condition:
    $a at pe.entry_point
}