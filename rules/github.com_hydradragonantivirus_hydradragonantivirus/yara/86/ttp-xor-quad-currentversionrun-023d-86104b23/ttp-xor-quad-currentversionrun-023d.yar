rule TTP_XOR_QUAD_CurrentVersionRun_023d {
  strings:
    $key_023d = { 51 52 [2] 75 5c [2] 5e 70 [2] 70 52 [2] 64 49 [2] 6b 53 [2] 75 4e [2] 77 4f [2] 6c 49 [2] 70 4e [2] 6c 61 }

  condition:
    any of them
}