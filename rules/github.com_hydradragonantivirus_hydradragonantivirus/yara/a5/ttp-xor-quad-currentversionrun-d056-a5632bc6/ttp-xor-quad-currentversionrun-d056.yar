rule TTP_XOR_QUAD_CurrentVersionRun_d056 {
  strings:
    $key_d056 = { 83 39 [2] a7 37 [2] 8c 1b [2] a2 39 [2] b6 22 [2] b9 38 [2] a7 25 [2] a5 24 [2] be 22 [2] a2 25 [2] be 0a }

  condition:
    any of them
}