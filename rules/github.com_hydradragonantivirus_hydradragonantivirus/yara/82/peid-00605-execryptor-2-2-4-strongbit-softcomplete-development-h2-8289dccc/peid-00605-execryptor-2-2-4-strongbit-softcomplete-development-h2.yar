rule PEiD_00605_EXECryptor_2_2_4____Strongbit_SoftComplete_Development__h2__ {
  meta:
    description = "[EXECryptor 2.2.4 -> Strongbit/SoftComplete Development (h2)]"
    ep_only     = "true"

  strings:
    $a = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 ?? 00 00 00 }

  condition:
    $a
}