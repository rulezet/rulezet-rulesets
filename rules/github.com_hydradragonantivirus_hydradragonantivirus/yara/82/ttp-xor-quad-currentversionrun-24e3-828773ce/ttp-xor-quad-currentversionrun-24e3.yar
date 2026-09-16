rule TTP_XOR_QUAD_CurrentVersionRun_24e3 {
  strings:
    $key_24e3 = { 77 8c [2] 53 82 [2] 78 ae [2] 56 8c [2] 42 97 [2] 4d 8d [2] 53 90 [2] 51 91 [2] 4a 97 [2] 56 90 [2] 4a bf }

  condition:
    any of them
}