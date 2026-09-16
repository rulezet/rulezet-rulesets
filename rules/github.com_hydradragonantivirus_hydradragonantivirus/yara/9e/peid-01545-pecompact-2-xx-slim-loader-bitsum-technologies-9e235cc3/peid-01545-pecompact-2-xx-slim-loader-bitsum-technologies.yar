rule PEiD_01545_PeCompact_2_xx__Slim_Loader_____BitSum_Technologies_ {
  meta:
    description = "[PeCompact 2.xx (Slim Loader) -> BitSum Technologies]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

  condition:
    $a
}