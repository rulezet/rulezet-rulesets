rule TTP_XOR_QUAD_CurrentVersionRun_02ef {
  strings:
    $key_02ef = { 51 80 [2] 75 8e [2] 5e a2 [2] 70 80 [2] 64 9b [2] 6b 81 [2] 75 9c [2] 77 9d [2] 6c 9b [2] 70 9c [2] 6c b3 }

  condition:
    any of them
}