rule TTP_XOR_QUAD_CurrentVersionRun_15e3 {
  strings:
    $key_15e3 = { 46 8c [2] 62 82 [2] 49 ae [2] 67 8c [2] 73 97 [2] 7c 8d [2] 62 90 [2] 60 91 [2] 7b 97 [2] 67 90 [2] 7b bf }

  condition:
    any of them
}