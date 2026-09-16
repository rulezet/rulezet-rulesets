rule TTP_XOR_QUAD_CurrentVersionRun_dee3 {
  strings:
    $key_dee3 = { 8d 8c [2] a9 82 [2] 82 ae [2] ac 8c [2] b8 97 [2] b7 8d [2] a9 90 [2] ab 91 [2] b0 97 [2] ac 90 [2] b0 bf }

  condition:
    any of them
}