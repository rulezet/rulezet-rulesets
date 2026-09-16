rule TTP_XOR_QUAD_CurrentVersionRun_156d {
  strings:
    $key_156d = { 46 02 [2] 62 0c [2] 49 20 [2] 67 02 [2] 73 19 [2] 7c 03 [2] 62 1e [2] 60 1f [2] 7b 19 [2] 67 1e [2] 7b 31 }

  condition:
    any of them
}