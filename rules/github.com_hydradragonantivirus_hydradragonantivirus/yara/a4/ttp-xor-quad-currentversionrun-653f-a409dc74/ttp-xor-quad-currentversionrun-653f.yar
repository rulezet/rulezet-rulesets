rule TTP_XOR_QUAD_CurrentVersionRun_653f {
  strings:
    $key_653f = { 36 50 [2] 12 5e [2] 39 72 [2] 17 50 [2] 03 4b [2] 0c 51 [2] 12 4c [2] 10 4d [2] 0b 4b [2] 17 4c [2] 0b 63 }

  condition:
    any of them
}