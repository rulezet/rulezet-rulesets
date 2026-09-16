rule PEiD_01186_MS_Visual_C___v_8_DLL__h_small_sig1__ {
  meta:
    description = "[MS Visual C++ v.8 DLL (h-small sig1)]"
    ep_only     = "true"

  strings:
    $a = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 ?? ?? ?? FF 5D E9 D6 FE FF FF CC CC CC CC CC }

  condition:
    $a
}