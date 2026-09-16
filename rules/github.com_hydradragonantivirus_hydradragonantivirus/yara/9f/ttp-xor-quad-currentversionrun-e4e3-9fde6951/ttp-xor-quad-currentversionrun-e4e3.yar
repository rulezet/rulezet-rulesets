rule TTP_XOR_QUAD_CurrentVersionRun_e4e3 {
  strings:
    $key_e4e3 = { b7 8c [2] 93 82 [2] b8 ae [2] 96 8c [2] 82 97 [2] 8d 8d [2] 93 90 [2] 91 91 [2] 8a 97 [2] 96 90 [2] 8a bf }

  condition:
    any of them
}