rule TTP_XOR_QUAD_CurrentVersionRun_35e3 {
  strings:
    $key_35e3 = { 66 8c [2] 42 82 [2] 69 ae [2] 47 8c [2] 53 97 [2] 5c 8d [2] 42 90 [2] 40 91 [2] 5b 97 [2] 47 90 [2] 5b bf }

  condition:
    any of them
}