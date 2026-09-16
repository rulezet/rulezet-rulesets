rule TTP_XOR_WriteProcessMemory_9fd8 {
  strings:
    $key_9fd8 = { c8 aa [2] fa 88 [2] fc bd [2] d2 bd [2] ed a1 }

  condition:
    any of them
}