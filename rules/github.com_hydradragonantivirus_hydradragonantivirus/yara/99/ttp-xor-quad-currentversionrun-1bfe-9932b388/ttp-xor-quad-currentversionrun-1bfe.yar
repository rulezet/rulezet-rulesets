rule TTP_XOR_QUAD_CurrentVersionRun_1bfe {
  strings:
    $key_1bfe = { 48 91 [2] 6c 9f [2] 47 b3 [2] 69 91 [2] 7d 8a [2] 72 90 [2] 6c 8d [2] 6e 8c [2] 75 8a [2] 69 8d [2] 75 a2 }

  condition:
    any of them
}