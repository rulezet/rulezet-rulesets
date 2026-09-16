rule TTP_XOR_QUAD_CurrentVersionRun_351e {
  strings:
    $key_351e = { 66 71 [2] 42 7f [2] 69 53 [2] 47 71 [2] 53 6a [2] 5c 70 [2] 42 6d [2] 40 6c [2] 5b 6a [2] 47 6d [2] 5b 42 }

  condition:
    any of them
}