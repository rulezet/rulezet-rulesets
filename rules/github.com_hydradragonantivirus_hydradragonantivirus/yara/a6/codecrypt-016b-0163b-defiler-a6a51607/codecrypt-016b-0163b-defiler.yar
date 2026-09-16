import "pe"
rule _CodeCrypt_016b__0163b__defiler_ {
  meta:
    description = "CodeCrypt 0.16b - 0.163b -> defiler"

  strings:
    $0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

  condition:
    $0 at pe.entry_point
}