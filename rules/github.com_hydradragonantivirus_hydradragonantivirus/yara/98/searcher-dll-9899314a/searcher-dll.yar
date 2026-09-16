rule Searcher_dll
{
       meta:
              description = "Searcher-dll"
              thread_level = 3
              in_the_wild = true
              reference = "https://www.optiv.com/blog/autoit-scripting-in-pos-malware"

       strings:
              $a = "EncodePointer" wide ascii
              $b = "CONOUT$" wide ascii
              $c = "%s%i_%s_%i.log" wide ascii

       condition:
              $a and $b and $c
}