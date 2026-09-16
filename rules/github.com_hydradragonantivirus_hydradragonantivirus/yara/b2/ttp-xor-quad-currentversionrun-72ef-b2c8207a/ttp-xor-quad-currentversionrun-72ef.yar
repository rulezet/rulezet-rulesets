rule TTP_XOR_QUAD_CurrentVersionRun_72ef {
  strings:
    $key_72ef = { 21 80 [2] 05 8e [2] 2e a2 [2] 00 80 [2] 14 9b [2] 1b 81 [2] 05 9c [2] 07 9d [2] 1c 9b [2] 00 9c [2] 1c b3 }

  condition:
    any of them
}