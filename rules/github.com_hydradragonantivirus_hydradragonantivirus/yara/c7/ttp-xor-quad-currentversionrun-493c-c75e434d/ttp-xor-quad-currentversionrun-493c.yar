rule TTP_XOR_QUAD_CurrentVersionRun_493c {
  strings:
    $key_493c = { 1a 53 [2] 3e 5d [2] 15 71 [2] 3b 53 [2] 2f 48 [2] 20 52 [2] 3e 4f [2] 3c 4e [2] 27 48 [2] 3b 4f [2] 27 60 }

  condition:
    any of them
}