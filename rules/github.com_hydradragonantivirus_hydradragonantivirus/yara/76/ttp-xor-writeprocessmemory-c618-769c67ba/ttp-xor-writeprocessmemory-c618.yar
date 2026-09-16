rule TTP_XOR_WriteProcessMemory_c618 {
  strings:
    $key_c618 = { 91 6a [2] a3 48 [2] a5 7d [2] 8b 7d [2] b4 61 }

  condition:
    any of them
}