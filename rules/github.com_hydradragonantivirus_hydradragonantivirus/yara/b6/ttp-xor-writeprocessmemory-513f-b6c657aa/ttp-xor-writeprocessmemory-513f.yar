rule TTP_XOR_WriteProcessMemory_513f {
  strings:
    $key_513f = { 06 4d [2] 34 6f [2] 32 5a [2] 1c 5a [2] 23 46 }

  condition:
    any of them
}