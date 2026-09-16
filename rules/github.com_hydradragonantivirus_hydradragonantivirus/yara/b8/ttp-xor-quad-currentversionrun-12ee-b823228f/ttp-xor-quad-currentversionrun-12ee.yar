rule TTP_XOR_QUAD_CurrentVersionRun_12ee {
  strings:
    $key_12ee = { 41 81 [2] 65 8f [2] 4e a3 [2] 60 81 [2] 74 9a [2] 7b 80 [2] 65 9d [2] 67 9c [2] 7c 9a [2] 60 9d [2] 7c b2 }

  condition:
    any of them
}