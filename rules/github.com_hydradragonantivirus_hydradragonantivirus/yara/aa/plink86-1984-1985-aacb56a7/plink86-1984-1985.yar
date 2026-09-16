import "pe"
rule PLINK86_1984__1985 {
  strings:
    $a0 = { FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26 }

  condition:
    $a0 at pe.entry_point
}