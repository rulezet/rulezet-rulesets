rule TTP_XOR_QUAD_CurrentVersionRun_1dee {
  strings:
    $key_1dee = { 4e 81 [2] 6a 8f [2] 41 a3 [2] 6f 81 [2] 7b 9a [2] 74 80 [2] 6a 9d [2] 68 9c [2] 73 9a [2] 6f 9d [2] 73 b2 }

  condition:
    any of them
}