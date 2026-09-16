rule TTP_XOR_QUAD_CurrentVersionRun_4cfe {
  strings:
    $key_4cfe = { 1f 91 [2] 3b 9f [2] 10 b3 [2] 3e 91 [2] 2a 8a [2] 25 90 [2] 3b 8d [2] 39 8c [2] 22 8a [2] 3e 8d [2] 22 a2 }

  condition:
    any of them
}