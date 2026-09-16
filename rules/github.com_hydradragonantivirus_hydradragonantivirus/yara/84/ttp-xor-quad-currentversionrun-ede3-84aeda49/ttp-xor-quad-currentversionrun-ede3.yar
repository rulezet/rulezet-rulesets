rule TTP_XOR_QUAD_CurrentVersionRun_ede3 {
  strings:
    $key_ede3 = { be 8c [2] 9a 82 [2] b1 ae [2] 9f 8c [2] 8b 97 [2] 84 8d [2] 9a 90 [2] 98 91 [2] 83 97 [2] 9f 90 [2] 83 bf }

  condition:
    any of them
}