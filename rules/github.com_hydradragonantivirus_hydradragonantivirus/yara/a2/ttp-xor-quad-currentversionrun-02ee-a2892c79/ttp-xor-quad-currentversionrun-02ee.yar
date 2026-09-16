rule TTP_XOR_QUAD_CurrentVersionRun_02ee {
  strings:
    $key_02ee = { 51 81 [2] 75 8f [2] 5e a3 [2] 70 81 [2] 64 9a [2] 6b 80 [2] 75 9d [2] 77 9c [2] 6c 9a [2] 70 9d [2] 6c b2 }

  condition:
    any of them
}