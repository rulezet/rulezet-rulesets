rule glonass_65_exe {
	meta:
		description = "Auto-generated rule - file glonass-65.exe.malware"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "25bbdc3712725db0a0845e74b36c5df287d7912533c58dfe866f3f3bfe55c7b7"
	strings:
		$s1 = "C:\\cr08pn8j\\z\\sfnpn\\s2g9i3k\\9tn\\l\\mame\\1l0et\\9yetid9r\\79h.pdb" fullword ascii 
		$s2 = "ClassicExplorerSettings.exe" fullword wide 
		$s3 = "; ;\";2;8;<;?;C;C;I;O;U;Y;\\;];];_;d;f;h;k;n;q;u;y;z;" fullword ascii 
		$s4 = "Q9Q.KUK" fullword ascii 
		$s5 = "<)<*<,<-</</<2<2<9<F<M<M<O<T<V<Z<[<k<o<p<r<s<s<t<u<z<" fullword ascii 
		$s6 = "> >\">0>1>1>6>8>=>=>B>E>H>T>V>\\>e>j>j>v>w>x>y>" fullword ascii 
		$s7 = ": :):-:0:5:::F:G:G:X:Y:Z:]:d:d:h:h:l:n:n:u:" fullword ascii 
		$s8 = "=#='=,=0=4=:=<===H=T=[=f=m=u=w=x=y=z={=|=}=" fullword ascii 
		$s9 = "0xba%u%u%d" fullword wide 
		$s10 = "t -qKu" fullword ascii 
		$s11 = "]/`d -eh" fullword ascii 
		$s12 = "hhhhee" fullword ascii 
		$s13 = "ME -MM='" fullword ascii 
		$s14 = "Copyright (C) 2009-2015, Ivo Beltchev" fullword wide 
		$s15 = "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[" fullword ascii 
		$s16 = "JPHROE" fullword ascii 
		$s17 = "$-- +kNNkkkkNNNN" fullword ascii 
		$s18 = "\\\\0RD\"MLI  " fullword ascii 
		$s19 = "[[[[[[[[[[[[[[[[[[" fullword ascii 
		$s20 = "[[[[[[[[[[[[[[[[[[[[[[" fullword ascii 
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 10 of ($s*) ) ) or ( all of them )
}