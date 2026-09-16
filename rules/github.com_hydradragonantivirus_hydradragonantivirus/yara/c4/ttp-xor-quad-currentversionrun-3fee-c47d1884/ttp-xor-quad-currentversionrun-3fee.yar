rule TTP_XOR_QUAD_CurrentVersionRun_3fee {
  strings:
    $key_3fee = { 6c 81 [2] 48 8f [2] 63 a3 [2] 4d 81 [2] 59 9a [2] 56 80 [2] 48 9d [2] 4a 9c [2] 51 9a [2] 4d 9d [2] 51 b2 }

  condition:
    any of them
}