rule TTP_XOR_QUAD_CurrentVersionRun_c2cc {
  strings:
    $key_c2cc = { 91 a3 [2] b5 ad [2] 9e 81 [2] b0 a3 [2] a4 b8 [2] ab a2 [2] b5 bf [2] b7 be [2] ac b8 [2] b0 bf [2] ac 90 }

  condition:
    any of them
}