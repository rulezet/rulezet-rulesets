rule TTP_XOR_QUAD_CurrentVersionRun_f4e3 {
  strings:
    $key_f4e3 = { a7 8c [2] 83 82 [2] a8 ae [2] 86 8c [2] 92 97 [2] 9d 8d [2] 83 90 [2] 81 91 [2] 9a 97 [2] 86 90 [2] 9a bf }

  condition:
    any of them
}