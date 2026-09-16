rule TTP_XOR_QUAD_CurrentVersionRun_4bfe {
  strings:
    $key_4bfe = { 18 91 [2] 3c 9f [2] 17 b3 [2] 39 91 [2] 2d 8a [2] 22 90 [2] 3c 8d [2] 3e 8c [2] 25 8a [2] 39 8d [2] 25 a2 }

  condition:
    any of them
}