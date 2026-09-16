rule TTP_XOR_QUAD_CurrentVersionRun_393f {
  strings:
    $key_393f = { 6a 50 [2] 4e 5e [2] 65 72 [2] 4b 50 [2] 5f 4b [2] 50 51 [2] 4e 4c [2] 4c 4d [2] 57 4b [2] 4b 4c [2] 57 63 }

  condition:
    any of them
}