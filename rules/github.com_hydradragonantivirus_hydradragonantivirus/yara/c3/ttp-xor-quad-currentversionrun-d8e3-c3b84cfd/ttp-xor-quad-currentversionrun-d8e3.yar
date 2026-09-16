rule TTP_XOR_QUAD_CurrentVersionRun_d8e3 {
  strings:
    $key_d8e3 = { 8b 8c [2] af 82 [2] 84 ae [2] aa 8c [2] be 97 [2] b1 8d [2] af 90 [2] ad 91 [2] b6 97 [2] aa 90 [2] b6 bf }

  condition:
    any of them
}