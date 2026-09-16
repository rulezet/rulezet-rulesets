rule PEiD_00604_EXECryptor_2_2_4____Strongbit_SoftComplete_Development__h1__ {
  meta:
    description = "[EXECryptor 2.2.4 -> Strongbit/SoftComplete Development (h1)]"
    ep_only     = "true"

  strings:
    $a = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }

  condition:
    $a
}