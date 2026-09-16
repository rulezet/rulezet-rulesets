rule TTP_XOR_QUAD_CurrentVersionRun_7dee {
  strings:
    $key_7dee = { 2e 81 [2] 0a 8f [2] 21 a3 [2] 0f 81 [2] 1b 9a [2] 14 80 [2] 0a 9d [2] 08 9c [2] 13 9a [2] 0f 9d [2] 13 b2 }

  condition:
    any of them
}