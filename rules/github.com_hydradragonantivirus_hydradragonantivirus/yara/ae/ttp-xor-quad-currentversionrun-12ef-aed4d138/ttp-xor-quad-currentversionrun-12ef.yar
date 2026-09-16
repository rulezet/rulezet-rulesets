rule TTP_XOR_QUAD_CurrentVersionRun_12ef {
  strings:
    $key_12ef = { 41 80 [2] 65 8e [2] 4e a2 [2] 60 80 [2] 74 9b [2] 7b 81 [2] 65 9c [2] 67 9d [2] 7c 9b [2] 60 9c [2] 7c b3 }

  condition:
    any of them
}