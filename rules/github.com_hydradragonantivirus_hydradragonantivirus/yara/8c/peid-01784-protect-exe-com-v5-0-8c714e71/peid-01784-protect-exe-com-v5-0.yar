rule PEiD_01784_PROTECT__EXE_COM_v5_0_ {
  meta:
    description = "[PROTECT! EXE/COM v5.0]"
    ep_only     = "true"

  strings:
    $a = { 1E 0E 0E 1F 07 }

  condition:
    $a
}