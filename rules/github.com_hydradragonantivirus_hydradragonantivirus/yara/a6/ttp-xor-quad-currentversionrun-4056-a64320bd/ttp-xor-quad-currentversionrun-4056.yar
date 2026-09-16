rule TTP_XOR_QUAD_CurrentVersionRun_4056 {
  strings:
    $key_4056 = { 13 39 [2] 37 37 [2] 1c 1b [2] 32 39 [2] 26 22 [2] 29 38 [2] 37 25 [2] 35 24 [2] 2e 22 [2] 32 25 [2] 2e 0a }

  condition:
    any of them
}