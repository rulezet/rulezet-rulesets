rule TTP_XOR_QUAD_CurrentVersionRun_353f {
  strings:
    $key_353f = { 66 50 [2] 42 5e [2] 69 72 [2] 47 50 [2] 53 4b [2] 5c 51 [2] 42 4c [2] 40 4d [2] 5b 4b [2] 47 4c [2] 5b 63 }

  condition:
    any of them
}