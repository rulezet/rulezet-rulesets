rule TTP_XOR_MULT_DOSStub_1334 {
  strings:
    $key_1334 = { 47 5c [2] 33 44 [2] 74 46 [2] 33 57 [2] 7d 5b [2] 71 51 [2] 66 5a [2] 7d 14 [2] 40 }

  condition:
    any of them
}