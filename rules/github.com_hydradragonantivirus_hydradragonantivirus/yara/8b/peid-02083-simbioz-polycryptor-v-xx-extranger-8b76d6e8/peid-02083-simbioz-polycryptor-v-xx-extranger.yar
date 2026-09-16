rule PEiD_02083_SimbiOZ_PolyCryptor_v_xx___Extranger_ {
  meta:
    description = "[SimbiOZ PolyCryptor v.xx-> Extranger]"
    ep_only     = "true"

  strings:
    $a = { 55 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 }

  condition:
    $a
}