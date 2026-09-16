rule TTP_XOR_QUAD_CurrentVersionRun_f8e3 {
  strings:
    $key_f8e3 = { ab 8c [2] 8f 82 [2] a4 ae [2] 8a 8c [2] 9e 97 [2] 91 8d [2] 8f 90 [2] 8d 91 [2] 96 97 [2] 8a 90 [2] 96 bf }

  condition:
    any of them
}